
rule m3e9_13b96b052b276f16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.13b96b052b276f16"
     cluster="m3e9.13b96b052b276f16"
     cluster_size="18"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="lethic shipup gepys"
     md5_hashes="['22d50858dcf62565cb2b90bfc1fd2c7b','232b5122993f2a12164bf28d2e6cbeb4','de1c7b8045df089702220d7d9263137c']"

   strings:
      $hex_string = { a86ef344a344ef3ca274f370ae69d37c9964eb49ab64d97cab3ca5889248b18fad66a29be41fba80c45ea4004c95b1d506aaa7a455a772d60cf19a9d37976b93 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
