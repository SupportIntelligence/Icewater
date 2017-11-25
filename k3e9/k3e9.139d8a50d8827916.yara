
rule k3e9_139d8a50d8827916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.139d8a50d8827916"
     cluster="k3e9.139d8a50d8827916"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma rontokbro"
     md5_hashes="['21f5672a064b419d20cc93f7dc34238e','29029bbfed1b40c824559ba9c25b5991','ee081a8c15d603343b2e4546b0bdab23']"

   strings:
      $hex_string = { 780d276068f93bd8b292164460dfe19b2fdcfbf6f5a2958f5e583a67e5c317964ee352102d7d844b70a681a54356c718eddbe92246cd3b1d63d4b1d3f1383fbf }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
