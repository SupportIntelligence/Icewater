
rule k3e9_69d09ce911eb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.69d09ce911eb0b12"
     cluster="k3e9.69d09ce911eb0b12"
     cluster_size="940"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="mywebsearch toolbar webtoolbar"
     md5_hashes="['00907f7223505ebf15c87c2f2eec4999','0090e53ab59494c27d254d351c6a8475','02f08621601657c70bc700d0fe4e07a8']"

   strings:
      $hex_string = { 2a324af71aa5fdfb65bdefa3047b78837e52a7b4d820191e90666e950a91ee3324b7512934edff586f779b36187c3526ae28506811e94dc19ac26af072c0bf57 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
