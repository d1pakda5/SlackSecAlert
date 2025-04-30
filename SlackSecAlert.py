# -*- coding: utf-8 -*-
# Burp Suite extension in Jython
# Sends Slack alerts when production domains are accessed
# Includes UI for Slack webhook, username, cooldown, and toggle switches

from burp import IBurpExtender, IHttpListener, ITab
from javax.swing import JPanel, JLabel, JTextField, JCheckBox, BoxLayout
from java.awt import Dimension
from java.io import ByteArrayInputStream
from java.lang import String
from java.net import URL
import time
import json
import threading

class BurpExtender(IBurpExtender, IHttpListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Slack Notifier for Production")

        # UI setup
        self.panel = JPanel()
        self.panel.setLayout(BoxLayout(self.panel, BoxLayout.Y_AXIS))

        self.usernameLabel = JLabel("Slack Username (for mention):")
        self.usernameField = JTextField(10)
        self.usernameField.setMaximumSize(Dimension(200, 24))
        self.panel.add(self.usernameLabel)
        self.panel.add(self.usernameField)

        self.webhookLabel = JLabel("Slack Webhook URL:")
        self.webhookField = JTextField(10)
        self.webhookField.setMaximumSize(Dimension(200, 24))
        self.panel.add(self.webhookLabel)
        self.panel.add(self.webhookField)

        self.cooldownLabel = JLabel("Cooldown Period (minutes):")
        self.cooldownField = JTextField("5", 5)
        self.cooldownField.setMaximumSize(Dimension(60, 24))
        self.panel.add(self.cooldownLabel)
        self.panel.add(self.cooldownField)

        self.alertOnBrowse = JCheckBox("Alert on Browse")
        self.alertOnActive = JCheckBox("Alert on Active Scan")
        self.panel.add(self.alertOnBrowse)
        self.panel.add(self.alertOnActive)

        self._callbacks.customizeUiComponent(self.panel)
        self._callbacks.addSuiteTab(self)
        self._callbacks.registerHttpListener(self)

        self.production_domains = self.load_production_domains()
        self.last_alert_times = {}

    def getTabCaption(self):
        return "Slack Notifier"

    def getUiComponent(self):
        return self.panel

    def load_production_domains(self):
        try:
            with open("production_domains.txt", "r") as f:
                return set(line.strip() for line in f if line.strip())
        except:
            print("Error loading production_domains.txt")
            return set()

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return

        request_info = self._helpers.analyzeRequest(messageInfo)
        http_service = messageInfo.getHttpService()
        url = str(request_info.getUrl())
        domain = http_service.getHost()

        if domain not in self.production_domains:
            return

        is_browse = toolFlag == self._callbacks.TOOL_PROXY
        is_active = toolFlag in [self._callbacks.TOOL_SCANNER, self._callbacks.TOOL_INTRUDER]

        if (self.alertOnBrowse.isSelected() and is_browse) or (self.alertOnActive.isSelected() and is_active):
            now = time.time()
            try:
                cooldown = int(self.cooldownField.getText().strip()) * 60
            except:
                cooldown = 300  # default to 5 min

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
            message_bytes = String(message).getBytes("UTF-8")
            url = URL(webhook_url)
            conn = url.openConnection()
            conn.setDoOutput(True)
            conn.setRequestMethod("POST")
            conn.setRequestProperty("Content-Type", "application/json")
            outputStream = conn.getOutputStream()
            outputStream.write(message_bytes)
            outputStream.flush()
            outputStream.close()

            response_code = conn.getResponseCode()
            if response_code != 200:
                print("Slack notification failed with HTTP code:", response_code)
            else:
                print("Slack notification sent successfully.")

        except Exception as e:
            print("Slack notification failed: %s" % e)
