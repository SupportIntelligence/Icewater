
rule n26bb_494a5cc1cc000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.494a5cc1cc000932"
     cluster="n26bb.494a5cc1cc000932"
     cluster_size="169"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="gandcrab ransom malicious"
     md5_hashes="['94d2e9b9aa105f5c1cacee0e4164d93fe76e6ae0','60e1fb171a4fd8a43f451ff71a64ccbc1444f931','32255e8f9112dd490b4c14c2ce65a48bcc2df85c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.494a5cc1cc000932"

   strings:
      $hex_string = { 4df051575056e82b80000083c41085c07405c60300eb558b45f4483945fc0f9cc183f8fc7c2a3bc77d2684c9740a8a064684c075f98846feff75288d45f06a01 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
