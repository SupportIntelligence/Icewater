
rule k3f8_6846ea41c0000130
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f8.6846ea41c0000130"
     cluster="k3f8.6846ea41c0000130"
     cluster_size="30"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="jisut ransom androidos"
     md5_hashes="['ac2417e59575213377ed8840efd5183d8da5822f','6fbdc89312d835343bf7ec0cc58c670a1624944e','c50e36b0e0f0c65ec5881fa5a49876a93db7379d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k3f8.6846ea41c0000130"

   strings:
      $hex_string = { 3b00184c6a6176612f6c616e672f537472696e674275666665723b0001560002564a0002564c0003564c490003564c4c000e57494e444f575f53455256494345 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
