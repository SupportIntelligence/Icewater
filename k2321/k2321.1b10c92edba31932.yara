
rule k2321_1b10c92edba31932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.1b10c92edba31932"
     cluster="k2321.1b10c92edba31932"
     cluster_size="7"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hupigon backdoor razy"
     md5_hashes="['66157b661b61eb81710b2a182ddc8b81','72fcdc42f3f9df7f6223f801dd34453e','dea029281e73dfca6e413f3925da1c45']"

   strings:
      $hex_string = { 6452d7a437798465e3a32f2b753d09b2be4e3059f992d621b9ee12de79ba9daac57e9307a125dafcae62f6551bbc8b4505ff6080aa39c1f5e0e55ee7ab8f35f0 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
