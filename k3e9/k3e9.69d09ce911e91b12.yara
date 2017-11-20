
rule k3e9_69d09ce911e91b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.69d09ce911e91b12"
     cluster="k3e9.69d09ce911e91b12"
     cluster_size="437"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="mywebsearch mindspark riskware"
     md5_hashes="['0141fc5274f976429bd71f1c5830499d','01d0ea59ac65d043ca8b20dfc282b0ca','0be8c76ba31fd653ce3bf1ae4bb2b7ff']"

   strings:
      $hex_string = { 9e281fba7f2227db873b429a5c2b0678fa830fe037809c2176ce8e386badee0aa2a8774f92c51dd5c1264708ebf6d1d29768946e2de4bff7c3bba4f082e6be24 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
