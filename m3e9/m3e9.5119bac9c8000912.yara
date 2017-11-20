
rule m3e9_5119bac9c8000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5119bac9c8000912"
     cluster="m3e9.5119bac9c8000912"
     cluster_size="36"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vbna vobfus pronny"
     md5_hashes="['01e22a45b3e15e3fcb5edb9218b4400c','0a1e271cbfb609e6a1e50f316cb63d04','a8beccf9bdab22b8ee182295c65cef0b']"

   strings:
      $hex_string = { 448197999abbc2bed5cacac6fcdafbfcfbfcfbf25d820338fd0000000000000000000000001bdf865b5b87678b8d8f4d567d7e929396989cb4b5b59f48c5d8cf }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
