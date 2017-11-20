
rule k3e9_69d09ce997ab0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.69d09ce997ab0b12"
     cluster="k3e9.69d09ce997ab0b12"
     cluster_size="30"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="mywebsearch mindspark webtoolbar"
     md5_hashes="['174443b8cf5c55deef92db04b4bb1068','28616d2bbb64e823700f0da8c41208ca','8fe1ea86b8ea7cd670538bc191f46f6d']"

   strings:
      $hex_string = { 2a324af71aa5fdfb65bdefa3047b78837e52a7b4d820191e90666e950a91ee3324b7512934edff586f779b36187c3526ae28506811e94dc19ac26af072c0bf57 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
