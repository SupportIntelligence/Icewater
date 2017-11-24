
rule n3e9_131a164dce9b1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.131a164dce9b1912"
     cluster="n3e9.131a164dce9b1912"
     cluster_size="10722"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor bayrob bundleinstaller"
     md5_hashes="['0003befa32ffa4ae89daae8beef80e19','00090f45cf0ffee19f5ff7949a0a908a','006600c6834255ba03ef1ac7148c62fe']"

   strings:
      $hex_string = { b4b41e9633adcf29f17139a1b2b0aa04e975ef0fd59a055ab8acc76a5ffe202a6f7651153f2c143cabe5b9f62dbc7f79a5f57a36705cdc80227735ca8f014131 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
