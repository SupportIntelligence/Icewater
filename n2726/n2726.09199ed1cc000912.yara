
rule n2726_09199ed1cc000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2726.09199ed1cc000912"
     cluster="n2726.09199ed1cc000912"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="symmi malicious stantinko"
     md5_hashes="['6070b9c779718ea1149c8af2837cd6ca773e0f0c','8b954e7524bef6c0934339e72d336fb1500457e2','48cb16524563d8d5cacd63646ae50190f0ccdd26']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2726.09199ed1cc000912"

   strings:
      $hex_string = { 00fb52228ac04981cf4d2a8f435f219c886a5cb89c6c7310e8f4acd5ff8bd9a100c576103d00c576107428f6403c020f845ebeffff807839047218536850942a }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
