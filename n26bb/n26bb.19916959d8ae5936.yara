
rule n26bb_19916959d8ae5936
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.19916959d8ae5936"
     cluster="n26bb.19916959d8ae5936"
     cluster_size="41"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="zusy tepfer autorun"
     md5_hashes="['60c49102c9a11b47636dfa6927c030c871265d12','e878790fe8d3ad9f86c174d6a80161635d399e22','d2bb599392bcc9b00dd92e7790938be68d48f746']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.19916959d8ae5936"

   strings:
      $hex_string = { cccc568bf1578bfa83fe01754485ff7435538a581380fb08732b33c98d90980000003848197611397a0c741d0fb670194183c2143bce7cef0fb6cb89bc886001 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
