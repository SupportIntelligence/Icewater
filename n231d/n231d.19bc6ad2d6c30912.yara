
rule n231d_19bc6ad2d6c30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231d.19bc6ad2d6c30912"
     cluster="n231d.19bc6ad2d6c30912"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="hiddad androidos hiddenads"
     md5_hashes="['68ed62fa507cc00c9a8f2819ca3e5dc6e2221418','84b085417811bdab5049f3095f0b24e8927c75b5','4b28c7a5dade492065547d49edf4eb1e4f221992']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231d.19bc6ad2d6c30912"

   strings:
      $hex_string = { 5300012e25035ddaff733307dfe34ec00b5e15e222e1c1082187113677dbfcfb0688e58ad92a8ec80289efcd9d4c97e92b52e64ab46dadcf8517f80f35fd10b9 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
