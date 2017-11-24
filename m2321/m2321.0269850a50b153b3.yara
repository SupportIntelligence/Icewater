
rule m2321_0269850a50b153b3
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0269850a50b153b3"
     cluster="m2321.0269850a50b153b3"
     cluster_size="49"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cpsg riskware adload"
     md5_hashes="['01eb5fa1992980d1cad1b94d496dd422','045c0aeabb0353c6fc421adcec2c6d1d','58047224a08020406c4f683294fcac46']"

   strings:
      $hex_string = { 7a595663861c7158d8043a854fd319e140c651892a64a3da030f162e15764973e2469dede8be536c959cb08e92ee07778279e0e328ef814b84bad40941311e42 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
