
rule o2706_6d14b9e9ca000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o2706.6d14b9e9ca000b32"
     cluster="o2706.6d14b9e9ca000b32"
     cluster_size="25"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="browsefox ursu malicious"
     md5_hashes="['e298e8ba0bd1f9ce715c37adba01a0d774a03f95','938c0390a6d699af39f68d72b0a4f7f85baa461b','14268768fac545f937a6886dc7eb3136e181d52b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o2706.6d14b9e9ca000b32"

   strings:
      $hex_string = { 5f44656661756c7453657474696e677300666f726d61740074696d655a6f6e6548616e646c696e67006363363830303831393335333330383635646134623162 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
