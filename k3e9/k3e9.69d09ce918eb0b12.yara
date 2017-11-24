
rule k3e9_69d09ce918eb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.69d09ce918eb0b12"
     cluster="k3e9.69d09ce918eb0b12"
     cluster_size="237"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="mywebsearch toolbar riskware"
     md5_hashes="['00e38b11581b2354d5e82dcccb285076','01887be544e1fd5e6f0767bf274354a3','0f7c7d70c27f608070729d83c93e6b49']"

   strings:
      $hex_string = { 2a324af71aa5fdfb65bdefa3047b78837e52a7b4d820191e90666e950a91ee3324b7512934edff586f779b36187c3526ae28506811e94dc19ac26af072c0bf57 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
