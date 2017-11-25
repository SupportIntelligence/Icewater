
rule n3e9_131c9ec9c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.131c9ec9c4000b32"
     cluster="n3e9.131c9ec9c4000b32"
     cluster_size="4154"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="viking jadtre nimnul"
     md5_hashes="['000b27812ba07617bb64864b58ce6ee0','00a33ead4cb76e0380164945a427a20a','0454b3677c4257c51c9e09271268f8a9']"

   strings:
      $hex_string = { 5a99150758c67be0a92f2b0629e94223d533af3cee4c17c48212bb24c8664502f63f7d8a5e57de8932615f2dd2a32708ba266b8551bdcc2ce4c0d896e5e23d77 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
