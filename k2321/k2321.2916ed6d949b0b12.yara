
rule k2321_2916ed6d949b0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2916ed6d949b0b12"
     cluster="k2321.2916ed6d949b0b12"
     cluster_size="5"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy emotet"
     md5_hashes="['39d4738b95b09654a9e7b7e40b8253ac','8e01b56f7cb3176b7e7afaa10afb9d73','d78e8c372ad54303db024e8803f990bb']"

   strings:
      $hex_string = { 8a3323929b13c9cd8d64e784b32687b05203d9495a6eb846acd72a95729980bcbdeecbf06beff37d2683c366898402b54211a05107aa157aa534482d0e578ba2 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
