
rule n3f8_63b852b49aeb1112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.63b852b49aeb1112"
     cluster="n3f8.63b852b49aeb1112"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos piom vmvol"
     md5_hashes="['d5575225634466a5bf50e4dee570e2fa3c02ea5f','c9dd69bbc090c59202512c7d50efa1838afafe26','58986398f78985afaca61d6fd485eefd31bf876e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.63b852b49aeb1112"

   strings:
      $hex_string = { 020b13000013039d0182130000140384015c0f00001603cc02ad10000017036104260c000017033a056c0f0000170361044211000018037805110d0000180374 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
