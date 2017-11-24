
rule k2321_2914ad6994bb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2914ad6994bb0b12"
     cluster="k2321.2914ad6994bb0b12"
     cluster_size="45"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba emotet zusy"
     md5_hashes="['08d98f9b253339e6f17333eec3a299ce','0c231d512166355e247fd56810bb0645','533bf08c6cf5be6f4428cdff28c0dd35']"

   strings:
      $hex_string = { 1ec9cd8de4ce8864e786b32687b05203d9495a6eb846acd72a95729980bcbdeecbf06beff37d2683c366898402b54211a05107aa157aa534482d0e578ba2d4c2 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
