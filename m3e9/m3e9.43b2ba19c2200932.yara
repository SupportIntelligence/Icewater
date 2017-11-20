
rule m3e9_43b2ba19c2200932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.43b2ba19c2200932"
     cluster="m3e9.43b2ba19c2200932"
     cluster_size="45"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus jorik ezvy"
     md5_hashes="['07bfdc3966ca71e86c19d014e7e00e1d','149ace8546dc6c33ae6276c910da4194','a8a20a54b128fedd35f9f10bc18b7b2c']"

   strings:
      $hex_string = { 448197999abbc2bed5cacac6fcdafbfcfbfcfbf25d820338fd0000000000000000000000001bdf865b5b87678b8d8f4d567d7e929396989cb4b5b59f48c5d8cf }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
