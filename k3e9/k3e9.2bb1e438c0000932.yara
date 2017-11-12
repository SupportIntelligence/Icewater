
rule k3e9_2bb1e438c0000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2bb1e438c0000932"
     cluster="k3e9.2bb1e438c0000932"
     cluster_size="182"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="bxvp small trojanclicker"
     md5_hashes="['02f76e13f75012f1b08a9abdb4c52954','02fa6225a3ef4cd3714f094b599cd575','184b54da1955e99d239c35d134746e09']"

   strings:
      $hex_string = { 6f634164647265737300007f014765744d6f64756c6548616e646c65410000b70147657453746172747570496e666f41004b45524e454c33322e646c6c0000be }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
