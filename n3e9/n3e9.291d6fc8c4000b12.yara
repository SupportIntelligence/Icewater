import "hash"

rule n3e9_291d6fc8c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.291d6fc8c4000b12"
     cluster="n3e9.291d6fc8c4000b12"
     cluster_size="156 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vbkrypt injector backdoor"
     md5_hashes="['dc024215bedeceb42ce599808aa91e1f', '716d823a4e96dc0b40b0ed0a025243ae', 'b34d779097642474d48f6e0b672c2d6f']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(49152,1024) == "afc2cff43ec58a5447a4d9d0b647b557"
}

