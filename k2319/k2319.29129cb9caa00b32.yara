
rule k2319_29129cb9caa00b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.29129cb9caa00b32"
     cluster="k2319.29129cb9caa00b32"
     cluster_size="21"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['587ec49de59dd468a5c81a16f60795493aade5df','0f41ad7d5624deed3a2f65dde12cb89099d3262f','80a313ea917675e85fd9a8aab7b5288100ad68a5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.29129cb9caa00b32"

   strings:
      $hex_string = { 3245323f38333a28307845312c3078313730292929627265616b7d3b666f72287661722059385220696e206d33563852297b6966285938522e6c656e6774683d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
