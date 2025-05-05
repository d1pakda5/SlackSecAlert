# -*- coding: utf-8 -*-
# Burp Suite extension in Jython
# Sends Slack alerts when production domains are accessed
# Includes UI for Slack webhook, username, cooldown, and toggle switches

from burp import IBurpExtender, IHttpListener, ITab
from javax.swing import JPanel, JLabel, JTextField, JCheckBox, JButton, BoxLayout
from java.awt import BorderLayout, Dimension
from java.util import Date
import time
import json
import threading
import re
import urllib2

class BurpExtender(IBurpExtender, IHttpListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Slack Notifier for Production")

        self.panel = JPanel()
        self.panel.setLayout(BoxLayout(self.panel, BoxLayout.Y_AXIS))

        stored_username = callbacks.loadExtensionSetting("slack_username") or ""
        stored_webhook = callbacks.loadExtensionSetting("slack_webhook") or ""
        stored_cooldown = callbacks.loadExtensionSetting("slack_cooldown") or "5"

        self.usernameLabel = JLabel("Slack Username (for mention):")
        self.usernameField = JTextField(stored_username, 10)
        self.usernameField.setMaximumSize(Dimension(150, 24))
        self.panel.add(self.usernameLabel)
        self.panel.add(self.usernameField)

        self.webhookLabel = JLabel("Slack Webhook URL:")
        self.webhookField = JTextField(stored_webhook, 10)
        self.webhookField.setMaximumSize(Dimension(150, 24))
        self.panel.add(self.webhookLabel)
        self.panel.add(self.webhookField)

        self.cooldownLabel = JLabel("Cooldown Period (minutes):")
        self.cooldownField = JTextField(stored_cooldown, 5)
        self.cooldownField.setMaximumSize(Dimension(60, 24))
        self.panel.add(self.cooldownLabel)
        self.panel.add(self.cooldownField)

        self.saveButton = JButton("Save Settings", actionPerformed=self.save_settings)
        self.panel.add(self.saveButton)

        self.alertOnBrowse = JCheckBox("Alert on Browse")
        self.alertOnActive = JCheckBox("Alert on Active Scan")
        self.panel.add(self.alertOnBrowse)
        self.panel.add(self.alertOnActive)

        self._callbacks.customizeUiComponent(self.panel)
        self._callbacks.addSuiteTab(self)
        self._callbacks.registerHttpListener(self)

        self.production_domains = self.load_production_domains()
        self.last_alert_times = {}

    def save_settings(self, event):
        self._callbacks.saveExtensionSetting("slack_username", self.usernameField.getText().strip())
        self._callbacks.saveExtensionSetting("slack_webhook", self.webhookField.getText().strip())
        self._callbacks.saveExtensionSetting("slack_cooldown", self.cooldownField.getText().strip())
        print("Slack Notifier settings saved.")

    def getTabCaption(self):
        return "Slack Notifier"

    def getUiComponent(self):
        return self.panel

    def load_production_domains(self):
        try:
            with open("production_domains.txt", "r") as f:
                return set(line.strip() for line in f if line.strip())
        except:
            return set()

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return

        request_info = self._helpers.analyzeRequest(messageInfo)
        http_service = messageInfo.getHttpService()
        url = str(self._helpers.analyzeRequest(messageInfo).getUrl())
        domain = http_service.getHost()

        if domain not in self.production_domains:
            return

        is_browse = toolFlag == self._callbacks.TOOL_PROXY
        is_active = toolFlag == self._callbacks.TOOL_SCANNER

        if (self.alertOnBrowse.isSelected() and is_browse) or (self.alertOnActive.isSelected() and is_active):
            now = time.time()
            try:
                cooldown = int(self.cooldownField.getText().strip()) * 60
            except:
                cooldown = 300

            if domain in self.last_alert_times and now - self.last_alert_times[domain] < cooldown:
                return
            self.last_alert_times[domain] = now

            slack_webhook = self.webhookField.getText().strip()
            slack_user = self.usernameField.getText().strip()
            if not slack_webhook:
                print("Slack webhook URL is not configured.")
                return

            msg = self.format_slack_message(domain, url, slack_user)
            threading.Thread(target=self.send_slack_notification, args=(slack_webhook, msg)).start()

    def format_slack_message(self, domain, url, slack_user):
        return json.dumps({
            "blocks": [
                {"type": "header", "text": {"type": "plain_text", "text": ":mag: Burp Suite Activity Detected on Production"}},
                {"type": "section", "fields": [
                    {"type": "mrkdwn", "text": "*Environment:*\nProduction"},
                    {"type": "mrkdwn", "text": "*Domain:*\n`%s`" % domain}
                ]},
                {"type": "section", "fields": [
                    {"type": "mrkdwn", "text": "*URL Accessed:*\n<%s>" % url},
                    {"type": "mrkdwn", "text": "*Time:*\n%s" % time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
                ]},
                {"type": "context", "elements": [
                    {"type": "mrkdwn", "text": ":information_source: This activity is part of security testing. SREs may safely ignore unless unexpected. Contact <@%s> if unsure." % slack_user}
                ]}
            ]
        })

    def send_slack_notification(self, webhook_url, message):
        try:
            req = urllib2.Request(webhook_url, message, {'Content-Type': 'application/json'})
            urllib2.urlopen(req)
        except Exception as e:
            print("Slack notification failed: %s" % e)
