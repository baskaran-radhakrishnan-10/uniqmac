/***************************************************
 * 
 * This software is the confidential and proprietary information of Jamcracker, Inc. 
 * ("Confidential Information").  You shall not disclose such Confidential Information
 *  and shall use it only in accordance with the terms of the license agreement you 
 *  entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc.  All Rights    
 *  Reserved
 *
 * @ClassName: DashboardAction.java
 * @version: 1.0
 * @since: Jan 14, 2010
 * @author: Suresh
 * @see
 * 
 */
package com.jamcracker.common.security.saml.impl.util;


import java.io.CharArrayWriter;
import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import com.jamcracker.common.JCProperties;
import com.jamcracker.common.exception.JCBaseRunTimeException;
import com.jamcracker.common.security.validator.exception.ValidatorFaultCode;

import freemarker.template.Configuration;
import freemarker.template.DefaultObjectWrapper;
import freemarker.template.Template;

public class TemplateReader {

	private static Configuration configuration;
	private static Map<String, Template> contentTempateCache = new HashMap<String, Template>();
	private static final org.apache.log4j.Logger LOG = org.apache.log4j.Logger.getLogger(TemplateReader.class.getName());
	private static final String CONTENT_TEMPLATES_PATH = JCProperties.getPPConfigHome()+ "/saml/templates";

	static {
		init();
	}

	/**
	 * Reads content templates and process and returns
	 * 
	 * @param templateName
	 * @param params
	 * @return
	 * @throws Exception
	 */
	public static String getContentTemplate(String templateName, Map params) throws Exception {
		LOG.info("Start ContentTemplate.getContentTemplate()");

		// reading from cache
		Locale locale = null;
		Template template = contentTempateCache.get(templateName);

		if (params != null) {
			locale = (Locale) params.get("locale");
		}

		template = null;
		if (template == null) {
			if (locale != null) {
				template = configuration.getTemplate(templateName, locale);
			} else {
				template = configuration.getTemplate(templateName);
			}

			contentTempateCache.put(templateName, template);
		}

		LOG.debug("template:" + template);
		CharArrayWriter writer = new CharArrayWriter();
		template.process(params, writer);

		LOG.info("End ContentTemplate.getContentTemplate()");
		return (writer.toString());
	}
	
	/**
	 * Fetches the content template.
	 * 
	 * @param templateName the name of the template.
	 * @param locale the user specific locale.
	 * @return template, the {@code Template} object.
	 * @throws Exception
	 */
	public static Template getTemplate(String templateName, String locale) throws Exception {
		LOG.info("getTemplate() : START");

		Template template = contentTempateCache.get(templateName);

		if (locale != null) {
			
			try {
				template = configuration.getTemplate(templateName, locale);
			} catch (IOException e) {
				// load global template if locale specific file not found.
				template = configuration.getTemplate(templateName);
			}
			
		} else {
			template = configuration.getTemplate(templateName);
		}

		contentTempateCache.put(templateName, template);

		LOG.info("getTemplate() : END");
		return template;
	}
	
	/**
	 * Processes the content template based on the {@code objectParams}.
	 * 
	 * @param template the {@code Template} object.
	 * @param objectMap the place holder map object.
	 * @return content, the processed template String content.
	 * @throws Exception
	 */
	public static String processTemplate(Template template, Map<?,?> objectMap) throws Exception {
		LOG.info("processTemplate() : START");

		CharArrayWriter writer = new CharArrayWriter();
		template.process(objectMap, writer);
		
		LOG.info("processTemplate() : END");
		return writer.toString();
	}
	/**
	 * Reads the custom template, process and returns.
	 * @return String
	 * @throws Exception
	 */
	public static String getCustomContentTemplate (String customtemplate,  Map params) throws Exception {
		LOG.info("End ContentTemplate.getCustomContentTemplate() starts");
		Configuration cfg = new Configuration();
		Template template = new Template ("customtemplate", new StringReader(customtemplate), configuration, null);
		CharArrayWriter writer = new CharArrayWriter();
		template.process(params, writer);
		
		LOG.info("End ContentTemplate.getCustomContentTemplate() Ends");
		return (writer.toString());
	}
	
	/**
	 * Initiating configuration
	 */
	public static void init() {
		LOG.info("Start ContentTemplate.init()");

		try {
			configuration = new Configuration();
			LOG.debug("Content templates Path:" + CONTENT_TEMPLATES_PATH);
			configuration.setDirectoryForTemplateLoading(new File(CONTENT_TEMPLATES_PATH));
			configuration.setObjectWrapper(new DefaultObjectWrapper());
			configuration.setNumberFormat("#");

		LOG.info("End ContentTemplate.init()");
		} catch (Exception e) {
			LOG.error("Exception occured in init method ",e);
			throw new JCBaseRunTimeException(ValidatorFaultCode.LOAD_PROPERTIES_FAILED);
		}
	}
}