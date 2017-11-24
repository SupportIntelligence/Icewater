
rule n2321_339a6886dce2e112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.339a6886dce2e112"
     cluster="n2321.339a6886dce2e112"
     cluster_size="19"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fileinfector gate aovhryb"
     md5_hashes="['21480d748e6180c56f6ccf65fb861e42','27de4cf70f0e0447a7ce4b1cf2bd2ea2','ce9bd55a26e3d9f90301536f83604a57']"

   strings:
      $hex_string = { b344ad5ffb576ccacddfd05e22889a8ab066a016cccb03918d5090e4f135f2d733c8f6b8d46b73e68128f35284ffeff0045d5abf3a30142faee9fc19fa80c69f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
