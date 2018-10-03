
rule n26bb_49b6ad5cc9a11932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.49b6ad5cc9a11932"
     cluster="n26bb.49b6ad5cc9a11932"
     cluster_size="7597"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="autoit dangerousobject multi"
     md5_hashes="['cdd3e0d17e2cd9c49d87c967a00c83c5bcfd92b3','29fd51cbd633428b08dbcef5835670d40ed45822','b5a6405d9a79e8eeaf1f0a7340e1bad4b44251c7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.49b6ad5cc9a11932"

   strings:
      $hex_string = { 3bc77513ff150823480085c0740950e8aa7affff59ebcf8bc6c1f8058b048520964a0083e61fc1e6068d4430048020fd8b45f88b55fc5f5ec9c36a1468e0d348 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
