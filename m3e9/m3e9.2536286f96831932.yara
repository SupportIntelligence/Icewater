
rule m3e9_2536286f96831932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.2536286f96831932"
     cluster="m3e9.2536286f96831932"
     cluster_size="12"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="madangel small madang"
     md5_hashes="['421c7136fcd4a42cea3b95398e79ac98','4d2e3fcb6c3a5f6343ae825a8bd8d295','d0c9ddb3a7f5566a39dededcacfd0a57']"

   strings:
      $hex_string = { 656e7450726f63657373496400e81700000052656769737465725365727669636550726f6365737300e806000000536c65657000e8080000005f6c636c6f7365 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
