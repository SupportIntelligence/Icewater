
rule k3ec_351dc6b9c19b0b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.351dc6b9c19b0b32"
     cluster="k3ec.351dc6b9c19b0b32"
     cluster_size="18"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="malicious engine heuristic"
     md5_hashes="['06f5416687709a4e6cc32164aee6219e','1e5ffbc1575e275feb3d50e2b70a2a15','ccf7005f840cd111122c2de48e5ed179']"

   strings:
      $hex_string = { b742142bf153570fb77a0633db03d033c085ff741a8d4a248b113bf272098bde2bda3b71fc72084083c1283bc772e93bc7746940803d65b54100008945f47520 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
