
rule m2321_0269850a50b152b3
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0269850a50b152b3"
     cluster="m2321.0269850a50b152b3"
     cluster_size="241"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cpsg adload riskware"
     md5_hashes="['00c6f88252171896be9d8a4781ac9f32','01dc11e69436707f23bbe927ba1c3593','11edccc45460d514b4fe1e2c7e707dc9']"

   strings:
      $hex_string = { 7a595663861c7158d8043a854fd319e140c651892a64a3da030f162e15764973e2469dede8be536c959cb08e92ee07778279e0e328ef814b84bad40941311e42 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
