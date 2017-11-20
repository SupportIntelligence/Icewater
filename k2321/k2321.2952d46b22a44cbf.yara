
rule k2321_2952d46b22a44cbf
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2952d46b22a44cbf"
     cluster="k2321.2952d46b22a44cbf"
     cluster_size="21"
     filetype = "PE32 executable (DLL) (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="graftor nitol riskware"
     md5_hashes="['06f4ce68f9345e8daaff496de55c468e','0f27129710c48ecd3f0bf04d25e194b6','c9b8e3897d58f418bc1b25d8b8adc688']"

   strings:
      $hex_string = { 6a84e24d40ebf622526531b950bc1e1afd9b5e1d38ee2a0ca31711cd4a5f4277a4cf78c591de765c932d4fff5d472ab6b30bcc278c7c329dd51c3daba983a52f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
