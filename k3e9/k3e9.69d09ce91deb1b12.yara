
rule k3e9_69d09ce91deb1b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.69d09ce91deb1b12"
     cluster="k3e9.69d09ce91deb1b12"
     cluster_size="99"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="mywebsearch mindspark riskware"
     md5_hashes="['0125283172f7951b94f4d567b18304e4','02642890e3c608120fb8458b408bb651','2c4f67fd2d21974ffa9b581ea85c88f4']"

   strings:
      $hex_string = { 2a324af71aa5fdfb65bdefa3047b78837e52a7b4d820191e90666e950a91ee3324b7512934edff586f779b36187c3526ae28506811e94dc19ac26af072c0bf57 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
