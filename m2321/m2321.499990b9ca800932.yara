
rule m2321_499990b9ca800932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.499990b9ca800932"
     cluster="m2321.499990b9ca800932"
     cluster_size="9"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="midie shodi virut"
     md5_hashes="['0fbf2bcfcffdf96b95b94d7d21e8cca3','25314d25d1ed520fe481050fd69bc143','fdf77d4e987881b83246a7ec319b082c']"

   strings:
      $hex_string = { e717c23609b7ba281aefb94e08b63bd95a0e698f00f0a89abf2e3975fdc026f9d500d25b620f6ec390e4dab420c4c7b80104948c386b7ddfa5653ac6d4ab859e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
