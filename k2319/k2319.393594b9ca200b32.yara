
rule k2319_393594b9ca200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.393594b9ca200b32"
     cluster="k2319.393594b9ca200b32"
     cluster_size="57"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script adinject"
     md5_hashes="['681284869f7dc759f4534ae19b2ebcb4fccd3d58','dffe886f7bab764b6cd19e0da9178fbc6bd43080','280f67d6825becaaed5efb650dd57f0665628679']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.393594b9ca200b32"

   strings:
      $hex_string = { 3132392e292929627265616b7d3b7661722047326838673d7b27693948273a2256222c2762314d273a226e222c27443067273a66756e6374696f6e2864392c44 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
