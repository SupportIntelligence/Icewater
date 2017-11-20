
rule k3f4_02a454d69ba91114
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f4.02a454d69ba91114"
     cluster="k3f4.02a454d69ba91114"
     cluster_size="100"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="krypt bladabindi bkdr"
     md5_hashes="['03e161325fccc2bb25f5715f466ec733','065eaa82cd934344aa92e783c9bf6b89','25524f51b4ccdfd959ad03c3d7af4b8f']"

   strings:
      $hex_string = { 03e1120d0809018705f60619015d132f0819016213370811036d133e088100d00f850191007613140711037f134408190186044a08310295135608e900a513b7 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
