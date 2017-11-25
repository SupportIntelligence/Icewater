
rule k3f7_3312da9adcab0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.3312da9adcab0912"
     cluster="k3f7.3312da9adcab0912"
     cluster_size="79"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hidelink html script"
     md5_hashes="['006305b3db33cb9eff339c1a82a5c713','16479c66b2d3eaeb8094b1fe561e98dd','36720be271bcb88b99071f2143466fe7']"

   strings:
      $hex_string = { 322e31272c626c6f673a273239383630343233272c706f73743a2730277d293b0a09766172206c6f61645f636d63203d2066756e6374696f6e28297b6c696e6b }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
