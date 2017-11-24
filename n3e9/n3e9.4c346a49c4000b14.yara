
rule n3e9_4c346a49c4000b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4c346a49c4000b14"
     cluster="n3e9.4c346a49c4000b14"
     cluster_size="556"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="malicious riskware fsojcj"
     md5_hashes="['00a698615c87e3607a26ad14df3836fc','0185a4e3ec67e1664048f024c0b50633','0878ca5a681cb646ff38f5cc9510d7cf']"

   strings:
      $hex_string = { d97009feda710affda710affd97009feda710affd97009feda710affdf730afef7800afff5810e4bdd7c1d22dc7a1aebdb7715eddb7715eddb7715eddb7715ed }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
