
rule m2318_61356a88d8bb0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2318.61356a88d8bb0932"
     cluster="m2318.61356a88d8bb0932"
     cluster_size="15"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['15441e8dc8e1fcf36ace1d60e7ad97cc','1c89d8f84baa6748882caf9b96bc6228','ef3d8167c020ca5cb903751cae225378']"

   strings:
      $hex_string = { 44333638374644414439364438343343303546373342374336453042343133373043314139303536384132313936393732373932453845453242463130423534 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
