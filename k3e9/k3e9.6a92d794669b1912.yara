
rule k3e9_6a92d794669b1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6a92d794669b1912"
     cluster="k3e9.6a92d794669b1912"
     cluster_size="508"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="convertad nsis malicious"
     md5_hashes="['00136d53fccdb975a2c39a08af4dc793','0101c1b855cd03b1f1e5c56968a1c19d','081703eca742bf653b2bc7f5ca058d63']"

   strings:
      $hex_string = { d0327713b8cda281ccc12293d6e93e7d3494f3511fa17c990135a7a50aed12c2acbda9bfe8ddc062f8bb3d96b7be38230342927aecfd6effe6a4eadba347319f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
