
rule n3f7_29965a9dc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f7.29965a9dc6220b32"
     cluster="n3f7.29965a9dc6220b32"
     cluster_size="5"
     filetype = "ASCII text"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="riskware xafekopy clicker"
     md5_hashes="['446f9e76566f9ddd60ee4e0cb952dafc','4ea6685c8d44ac8e44af049de3ff00f6','fed98aec44c55b883475b8c3c236a3ea']"

   strings:
      $hex_string = { ac802b1d46ddbd76a5eeffa1588e9b6af4041932afadcd508544d099d30c696bc64c1548426892f9bbf240e9827b5107b69490777a60875716fc12251389b9e2 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
