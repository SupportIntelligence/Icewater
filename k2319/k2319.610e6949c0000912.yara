
rule k2319_610e6949c0000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.610e6949c0000912"
     cluster="k2319.610e6949c0000912"
     cluster_size="59"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="multiplug script browext"
     md5_hashes="['a67ceabe4faf6c1ad8dcad61b43a47963cbab128','3bc8a7f757f8b8486260101af24dccfce991cd01','87d2581c4af0270c8bee06ee58efa53358555a10']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.610e6949c0000912"

   strings:
      $hex_string = { 623c5a3b7d7d3b2866756e6374696f6e28297b766172204f373d22686f222c493d22656e74222c55373d226164222c56373d28307842353c2838312e2c313339 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
