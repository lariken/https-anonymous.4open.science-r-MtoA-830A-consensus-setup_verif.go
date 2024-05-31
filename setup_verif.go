<!-- index.html -->
<!DOCTYPE html>
<html lang="en" ng-app="anonymous-github" ng-controller="mainController">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
<title ng-bind="title">Anonymous Github</title>
<base href="/" />
<link rel="apple-touch-icon" sizes="180x180" href="/favicon/apple-touch-icon.png" />
<link rel="icon" type="image/png" sizes="32x32" href="/favicon/favicon-32x32.png" />
<link rel="icon" type="image/png" sizes="16x16" href="/favicon/favicon-16x16.png" />
<link rel="manifest" href="/favicon/site.webmanifest" />
<link rel="shortcut icon" href="/favicon.ico" />
<meta name="msapplication-config" content="/favicon/browserconfig.xml" />
<meta name="theme-color" content="#ffffff" />
<link rel="stylesheet" href="/css/all.min.css" />
</head>
<body keypress-events class="d-flex flex-column">
<ng-include src="'partials/header.htm'"></ng-include>
<ng-view class="align-items-stretch h-100 w-100 overflow-auto"></ng-view>
<div class="position-fixed bottom-0 right-0 p-3" style="z-index: 5; right: 0; bottom: 0">
<div id="liveToast" class="toast show" role="alert" aria-live="assertive" aria-atomic="true" data-delay="2000" ng-repeat="toast in toasts">
<div class="toast-header">
<strong class="mr-auto" ng-bind="toast.title"></strong>
<button type="button" class="ml-2 mb-1 close" data-dismiss="toast" aria-label="Close" ng-click="removeToast(toast);">
<span aria-hidden="true">&times;</span>
</button>
</div>
<div class="toast-body" ng-bind="toast.body"></div>
</div>
</div>
<script src="/script/bundle.min.js"></script>
<script>
      ace.config.set("basePath", "/script/external/ace/");
      PDFJS.workerSrc = "/script/external/pdf.worker.js";
    </script>
<script src="https://storage.ko-fi.com/cdn/scripts/overlay-widget.js"></script>
<script>
      kofiWidgetOverlay.draw("tdurieux", {
        type: "floating-chat",
        "floating-chat.donateButton.text": "Support me",
        "floating-chat.donateButton.background-color": "#323842",
        "floating-chat.donateButton.text-color": "#fff",
      });
    </script>
</body>
</html>
