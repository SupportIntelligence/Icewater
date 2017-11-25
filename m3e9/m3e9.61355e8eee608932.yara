
rule m3e9_61355e8eee608932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.61355e8eee608932"
     cluster="m3e9.61355e8eee608932"
     cluster_size="10761"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="byfh memscan vflooder"
     md5_hashes="['0000cbea542222e4ab735a4364fc4e04','002284632ed5efd7c53006f82a931cfa','00c3ffa51cbedf8b8607783c9db141ff']"

   strings:
      $hex_string = { 29dce8c431a52c8ec316303e5679229d8f4d1b0490d4eb7b6012584e37db55d13df3f7109a3a87920f88a662470075fed82e1823e3dd6e45fe7644a2be428abf }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
