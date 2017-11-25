
rule m3ec_41be5ec1cc001912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ec.41be5ec1cc001912"
     cluster="m3ec.41be5ec1cc001912"
     cluster_size="9"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['041812f385a1108addfa9ac724a09f0c','21ea368e780954487151d918397075f3','f80ec653826b54562c0f931f30600c23']"

   strings:
      $hex_string = { 45085333db568bf185c974268b551057bffeffff7f2bf92bd08d0c3785c9740d8a0c0284c974068808404e75ec5f85f6750648bb7a000780c600005e8bc35b5d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
