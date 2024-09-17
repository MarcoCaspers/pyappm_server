.PHONY: build
.PHONY: upload

clean:
	@echo "Cleaning the project..."
	@rm -rf dist > /dev/null 2>&1
	@echo "Clean completed successfully."

build:
	@echo "Building the project..."
	@mkdir dist > /dev/null 2>&1
	@zip -q -j ./dist/pyappm_server.zip ./src/pyappm_server/*.py ./src/pyappm_server/py.typed ./src/pyappm_server/pyappm_server ./src/pyappm_server/pyappm_server.service LICENSE.txt README.md CHANGELOG.md pyapp.toml requirements.txt > /dev/null 2>&1
	@echo "Build completed successfully."
	@echo "The build is located in the dist directory."

upload:
	@scp -r ./dist/pyappm_server.zip root@10.32.1.5:/inetpub/www/pyappm.nl/downloads
	@echo "Upload completed successfully."

all: clean build upload
	@echo "All tasks completed successfully."