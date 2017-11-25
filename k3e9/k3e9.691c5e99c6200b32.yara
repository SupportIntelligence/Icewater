
rule k3e9_691c5e99c6200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.691c5e99c6200b32"
     cluster="k3e9.691c5e99c6200b32"
     cluster_size="76979"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre waski generickd"
     md5_hashes="['00011b0924d7c75ab42184d5f169e0b0','000469467df45c185f93f1ef0335ab64','002f10e3361f617e71459b13fea7fa7e']"

   strings:
      $hex_string = { 412322ba360a3f5b5fc793d20ef42e666cff24807a58b18a4774b0bc44f4259115c5202bf1aaa4bd069d0934dd5c8627d5d6653a161eb8e570b5e17195350d11 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
