
rule m3ed_45b65cd4d992d311
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.45b65cd4d992d311"
     cluster="m3ed.45b65cd4d992d311"
     cluster_size="13"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bmnup"
     md5_hashes="['01b32b64a7a8249d49c447e9c56af81c','0584b7240616001077ffce23201777ba','db4a4c5e5eb0ef92fff78a16c40753f0']"

   strings:
      $hex_string = { 6119530a4481ce5d9f54a610de770da482d4d2934cab118d50adf02b1e14ede2c3644e264c84d768ccd071a0c8c558c6d5a1594f41af5ee72e83377eae21aa28 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
