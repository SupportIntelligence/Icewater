
rule k44a_46b6e749c0000914
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k44a.46b6e749c0000914"
     cluster="k44a.46b6e749c0000914"
     cluster_size="44"
     filetype = "application/x-sharedlib"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="mobidash androidos addisplay"
     md5_hashes="['011632000490cdb13da89a33ecd8f8ba','031be96cbb2124756d480db0fc9d2d86','5a4b066d7c4a7b8d6cb2c38301a51601']"

   strings:
      $hex_string = { f0ddfb1021891b07e0202fc2d80f2e4fd9039f002f50d10399a26b131c002915dd4900029124a8f1004018801a029b111c8446039303980138039004d30b6860 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
