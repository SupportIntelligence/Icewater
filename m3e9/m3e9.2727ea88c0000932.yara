
rule m3e9_2727ea88c0000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.2727ea88c0000932"
     cluster="m3e9.2727ea88c0000932"
     cluster_size="3509"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre trojandownloader kryptik"
     md5_hashes="['001e9867821e7e5d86c0aa9ca54290c2','00308c76abf6ac7d75441fbde4960839','0224495103665352b4ab4840baa421b2']"

   strings:
      $hex_string = { 43eda40fdadf83642ffb9ecb4aed7cbd0bd4c61b5845385442c4d2175e670661a8822aef702d6dcb1b44bcb829c2a213374ba607926983992512a1b95b6e488e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
