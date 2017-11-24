
rule n2321_0b132ccbc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.0b132ccbc6220b12"
     cluster="n2321.0b132ccbc6220b12"
     cluster_size="9"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nymaim razy bbyz"
     md5_hashes="['4a6f126468cd44a80f552770107eab48','6605eb620b07feaf11cd1c6de11886cf','f605cf7e0aee4c78739288bc9bb65cd9']"

   strings:
      $hex_string = { 823f2ae85f6933e0155b36fcbd9680920e71a101a78f6bb8482e8655418334c21f5c271eb0c7c7b521cad10b231b959efdd63cbcf5eb7d7817e6404dbad4cd4f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
