
rule n26d7_3114cce3e9691b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d7.3114cce3e9691b12"
     cluster="n26d7.3114cce3e9691b12"
     cluster_size="41"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="zusy malicious zvuzona"
     md5_hashes="['d7f5921a418ee9f20cc9b8862a8744d7282d2f5d','c491450988d29c958120fec5fd0d04d2d6d2080f','8781a51aff0a16bcd1ccfecc2f7ae1444dadb922']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d7.3114cce3e9691b12"

   strings:
      $hex_string = { bf88a14500e80ea2feff8b55fc52e8ea9c01008bc683c42032db8d5002668b0883c0026685c975f568ccb645002bc2d1f833c968040100005666894c46fae8ab }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
